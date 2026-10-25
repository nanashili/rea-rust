//! Per-command handlers: translate parsed CLI args/options into one or more
//! MCP tool invocations, mirroring `src/cli/**` and `src/application/**`.
use crate::analysis::{
    OpenOptions, cli_error, outcome, run_custom, run_direct_analysis, run_provider_analysis,
};
use crate::invoke::Runner;
use crate::output::FailureKind;
use crate::util::{absolute_caller_path, labelled, object};
use rea_core::analysis_error::{AnalysisError, InputIssue};
use serde_json::{Map, Value, json, value::RawValue};

const NATIVE_OPEN: [&str; 2] = ["snapshot", "provider"];

// ---------------------------------------------------------------------------
// Small accessors
// ---------------------------------------------------------------------------
fn get_str(value: &Value, key: &str) -> Option<String> {
    value.get(key).and_then(Value::as_str).map(str::to_owned)
}

fn option_strings(options: &Value, key: &str) -> Vec<String> {
    options
        .get(key)
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn arg_str<'a>(value: &'a Value, key: &str) -> &'a str {
    value.get(key).and_then(Value::as_str).unwrap_or_default()
}

fn present(value: &Value, key: &str) -> bool {
    value.get(key).is_some()
}

fn snake(key: &str) -> String {
    let mut out = String::with_capacity(key.len());
    for ch in key.chars() {
        if ch == '-' {
            out.push('_');
        } else if ch.is_ascii_uppercase() {
            out.push('_');
            out.push(ch.to_ascii_lowercase());
        } else {
            out.push(ch);
        }
    }
    out
}

fn renamed(key: &str, renames: &[(&str, &str)]) -> String {
    renames
        .iter()
        .find(|(from, _)| *from == key)
        .map(|(_, to)| (*to).to_owned())
        .unwrap_or_else(|| snake(key))
}

fn mapped_value(key: &str, value: &Value, path_args: &[&str]) -> Value {
    if path_args.contains(&key) {
        match value {
            Value::String(text) => Value::String(absolute_caller_path(text)),
            Value::Array(items) => Value::Array(
                items
                    .iter()
                    .map(|item| match item {
                        Value::String(text) => Value::String(absolute_caller_path(text)),
                        other => other.clone(),
                    })
                    .collect(),
            ),
            other => other.clone(),
        }
    } else {
        value.clone()
    }
}

fn open_options(options: &Value) -> OpenOptions {
    OpenOptions {
        snapshot: get_str(options, "snapshot"),
        provider: get_str(options, "provider"),
    }
}

/// Copy declared option keys into a tool-input map under renamed keys.
fn copy(into: &mut Map<String, Value>, options: &Value, pairs: &[(&str, &str)]) {
    for (cli, tool) in pairs {
        if let Some(value) = options.get(*cli) {
            into.insert((*tool).to_owned(), value.clone());
        }
    }
}

// ---------------------------------------------------------------------------
// Error projections
// ---------------------------------------------------------------------------
fn input_projection(
    operation: &str,
    path: &[&str],
    reason: &'static str,
    message: String,
    expected: Option<&str>,
) -> Value {
    let issue = InputIssue {
        path: path
            .iter()
            .map(|part| Value::String((*part).to_owned()))
            .collect(),
        reason,
        message: Some(message),
        expected: expected.map(|value| Value::String(value.to_owned())),
        minimum: None,
        maximum: None,
    };
    AnalysisError::input(operation, vec![issue]).project()
}

fn unavailable(operation: &str) -> Value {
    AnalysisError::capability_unavailable(
        "rea",
        operation,
        "This operation is not available in the native runtime build.",
    )
    .project()
}

// ---------------------------------------------------------------------------
// CLI selector (resolveCliAnalysisSelector)
// ---------------------------------------------------------------------------
fn resolve_selector(
    positional: Option<&str>,
    named: Option<&str>,
    option: &str,
    operation: &str,
) -> Result<String, Value> {
    if let (Some(positional), Some(named)) = (positional, named)
        && positional != named
    {
        return Err(input_projection(
            operation,
            &[option],
            "invalid_value",
            format!(
                "The positional selector and --{option} select different objects; supply one selector."
            ),
            None,
        ));
    }
    match named.or(positional) {
        Some(value) => Ok(value.to_owned()),
        None => Err(input_projection(
            operation,
            &[option],
            "missing_argument",
            format!(
                "Supply a positional selector or --{option}=<value>. Use the named option for values beginning with a dash."
            ),
            Some("string"),
        )),
    }
}

// ---------------------------------------------------------------------------
// Generic executors
// ---------------------------------------------------------------------------
fn direct(
    runner: &Runner<'_>,
    tool: &str,
    args: &Value,
    options: &Value,
    path_args: &[&str],
    renames: &[(&str, &str)],
) -> Value {
    let mut input = Map::new();
    for source in [args, options] {
        if let Some(object) = source.as_object() {
            for (key, value) in object {
                input.insert(renamed(key, renames), mapped_value(key, value, path_args));
            }
        }
    }
    match outcome(runner.invoke(tool, Value::Object(input))) {
        Ok(value) => value,
        Err(projection) => projection,
    }
}

fn provider(
    runner: &Runner<'_>,
    tool: &str,
    path: &str,
    options: &Value,
    path_args: &[&str],
    renames: &[(&str, &str)],
    extra: Vec<(&str, Value)>,
) -> Value {
    let mut input = Map::new();
    if let Some(object) = options.as_object() {
        for (key, value) in object {
            input.insert(renamed(key, renames), mapped_value(key, value, path_args));
        }
    }
    for (key, value) in extra {
        input.insert(key.to_owned(), value);
    }
    run_provider_analysis(runner, path, tool, Value::Object(input))
}

// ---------------------------------------------------------------------------
// JSON input (parseCliJsonInput): inline JSON or one local JSON file.
// ---------------------------------------------------------------------------
fn read_json_input(value: &str, operation: &str) -> Result<Value, Value> {
    if let Ok(parsed) = serde_json::from_str::<Value>(value) {
        return Ok(parsed);
    }
    match std::fs::read_to_string(value) {
        Ok(text) => serde_json::from_str::<Value>(&text)
            .map_err(|_| json_error(operation, value, "invalid-json")),
        Err(_) => {
            let trimmed = value.trim_start();
            if (trimmed.starts_with('{') || trimmed.starts_with('['))
                && !value.to_lowercase().ends_with(".json")
            {
                Err(json_error_inline(operation))
            } else {
                Err(json_error(operation, value, "read-failed"))
            }
        }
    }
}

/// Read inline JSON or one local JSON file without decoding its contents.
/// Exact-input handlers need this representation so JavaScript UTF-16 escape
/// sequences survive until the application parser owns their interpretation.
fn read_raw_json_input(value: &str, operation: &str) -> Result<Box<RawValue>, Value> {
    if let Ok(parsed) = serde_json::from_str::<Box<RawValue>>(value) {
        return Ok(parsed);
    }
    match std::fs::read_to_string(value) {
        Ok(text) => serde_json::from_str::<Box<RawValue>>(&text)
            .map_err(|_| json_error(operation, value, "invalid-json")),
        Err(_) => {
            let trimmed = value.trim_start();
            if (trimmed.starts_with('{') || trimmed.starts_with('['))
                && !value.to_lowercase().ends_with(".json")
            {
                Err(json_error_inline(operation))
            } else {
                Err(json_error(operation, value, "read-failed"))
            }
        }
    }
}

fn json_error_inline(operation: &str) -> Value {
    let projection = input_projection(
        operation,
        &[],
        "invalid_format",
        "JSON".to_owned(),
        Some("JSON"),
    );
    labelled("Application workflow failed", projection)
}

fn json_error(operation: &str, path: &str, reason: &str) -> Value {
    let projection = if reason == "invalid-json" {
        input_projection(
            operation,
            &[],
            "invalid_format",
            "JSON".to_owned(),
            Some("JSON"),
        )
    } else {
        input_projection(
            operation,
            &[],
            "invalid_value",
            format!("The JSON input file could not be read: {path}"),
            None,
        )
    };
    let mut envelope = labelled("Application workflow failed", projection);
    if let Some(object) = envelope.as_object_mut() {
        object.insert("input_path".to_owned(), Value::String(path.to_owned()));
        object.insert("input_reason".to_owned(), Value::String(reason.to_owned()));
    }
    envelope
}

/// Parse one `inputJson` arg and invoke `tool` with the parsed object.
fn json_whole(runner: &Runner<'_>, tool: &str, args: &Value, operation: &str) -> Value {
    match read_raw_json_input(arg_str(args, "inputJson"), operation) {
        Ok(value) => match outcome(runner.invoke_raw(tool, value)) {
            Ok(value) => value,
            Err(projection) => projection,
        },
        Err(error) => error,
    }
}

// ---------------------------------------------------------------------------
// xrefs symbol resolution (XrefsAddressResolution.ts)
// ---------------------------------------------------------------------------
fn resolve_xrefs_address(runner: &Runner<'_>, selector: &str) -> Result<String, Value> {
    let lower = selector.to_lowercase();
    let all_hex = !selector.is_empty() && selector.chars().all(|c| c.is_ascii_hexdigit());
    if selector.is_empty() || all_hex || lower.starts_with("0x") || lower.contains(":0x") {
        return Ok(selector.to_owned());
    }
    let inventory = match outcome(runner.invoke("list_names", json!({}))) {
        Ok(value) => value,
        Err(_) => return Ok(selector.to_owned()),
    };
    let Some(items) = inventory.as_array() else {
        return Ok(selector.to_owned());
    };
    let mut addresses: Vec<String> = Vec::new();
    for item in items {
        let value = item.get("value").and_then(Value::as_str);
        let address = item.get("address").and_then(Value::as_str);
        if let (Some(value), Some(address)) = (value, address)
            && value == selector
            && !address.is_empty()
            && !addresses.iter().any(|existing| existing == address)
        {
            addresses.push(address.to_owned());
        }
    }
    let quoted = serde_json::to_string(selector).unwrap_or_else(|_| format!("\"{selector}\""));
    match addresses.len() {
        1 => Ok(addresses.remove(0)),
        0 => Err(input_projection(
            "xrefs",
            &["address"],
            "invalid_value",
            format!(
                "Unknown analyzed symbol name {quoted}. Use an exact analyzed name or a hexadecimal address."
            ),
            None,
        )),
        _ => Err(input_projection(
            "xrefs",
            &["address"],
            "invalid_value",
            format!(
                "Analyzed symbol name {quoted} is ambiguous at {}. Select an exact address.",
                addresses.join(", ")
            ),
            None,
        )),
    }
}

// ---------------------------------------------------------------------------
// JavaScript application routing (analyze)
// ---------------------------------------------------------------------------
fn is_javascript_application_path(path: &str) -> bool {
    let lower = path.to_lowercase();
    if lower.ends_with(".asar") {
        return true;
    }
    let trimmed = lower.trim_end_matches(['/', '.']);
    if trimmed.ends_with(".app") {
        return false;
    }
    std::fs::metadata(path)
        .map(|meta| meta.is_dir())
        .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------
/// How a command's returned value is classified as a failure.
pub fn failure_kind(name: &str) -> FailureKind {
    match name {
        "capture-process" | "compare-process-captures" => FailureKind::ProcessCli,
        "setup" | "uninstall" | "update" => FailureKind::StatusField,
        "import-reference-source" => FailureKind::ImportFailed,
        _ => FailureKind::Inferred,
    }
}

/// Result of command execution before CLI formatting. Raw JSON remains
/// separate so the formatter never has to decode JavaScript lone surrogates.
pub enum CommandOutput {
    Value(Value),
    Raw(Box<RawValue>),
}

/// Execute one resolved command, returning its result value.
pub fn run_command(
    name: &str,
    args: &Value,
    options: &Value,
    runner: &Runner<'_>,
) -> CommandOutput {
    let value = match name {
        // ---- core binary (open / snapshot) --------------------------------
        "analyze" => run_analyze(runner, args, options),
        "inspect" => run_direct_analysis(
            runner,
            arg_str(args, "path"),
            "binary_overview",
            json!({}),
            &open_options(options),
        ),
        "decompile" => run_decompile(runner, args, options),
        "function" => run_selector_tool(
            runner,
            args,
            options,
            "analyze_function",
            "procedure",
            |s| json!({ "procedure": s }),
        ),
        "instructions" => run_selector_tool(
            runner,
            args,
            options,
            "read_function_instructions",
            "procedure",
            |s| json!({ "procedure": s }),
        ),
        "search" => run_search(runner, args, options),
        "xrefs" => run_xrefs(runner, args, options),
        "trace" => run_trace(runner, args, options),

        // ---- core native --------------------------------------------------
        "search-bytes" => {
            let mut input = Map::new();
            input.insert("pattern".to_owned(), json!(arg_str(args, "pattern")));
            copy(
                &mut input,
                options,
                &[
                    ("limit", "limit"),
                    ("mask", "mask"),
                    ("start", "start"),
                    ("end", "end"),
                    ("cursor", "cursor"),
                ],
            );
            run_direct_analysis(
                runner,
                arg_str(args, "path"),
                "search_bytes",
                Value::Object(input),
                &open_options(options),
            )
        }
        "inspect-native-load-image" => run_direct_analysis(
            runner,
            arg_str(args, "path"),
            "inspect_native_load_image",
            json!({}),
            &open_options(options),
        ),
        "read-bytes" => {
            let mut input = Map::new();
            input.insert("address".to_owned(), json!(arg_str(args, "address")));
            copy(&mut input, options, &[("length", "length")]);
            run_direct_analysis(
                runner,
                arg_str(args, "path"),
                "read_bytes",
                Value::Object(input),
                &open_options(options),
            )
        }
        "address-to-file-offset" => run_direct_analysis(
            runner,
            arg_str(args, "path"),
            "address_to_file_offset",
            json!({ "address": arg_str(args, "address") }),
            &open_options(options),
        ),
        "trace-native-values" => {
            let mut input = Map::new();
            input.insert("procedure".to_owned(), json!(arg_str(args, "procedure")));
            copy(
                &mut input,
                options,
                &[
                    ("maxDepth", "max_depth"),
                    ("maxFunctions", "max_functions"),
                    ("maxCallSites", "max_call_sites"),
                    ("maxNodes", "max_nodes"),
                    ("maxEdges", "max_edges"),
                    ("offset", "offset"),
                    ("limit", "limit"),
                ],
            );
            run_direct_analysis(
                runner,
                arg_str(args, "path"),
                "trace_native_values",
                Value::Object(input),
                &open_options(options),
            )
        }
        "inspect-native-data-type" => {
            let mut input = Map::new();
            copy(
                &mut input,
                options,
                &[("type", "type"), ("address", "address")],
            );
            run_direct_analysis(
                runner,
                arg_str(args, "path"),
                "inspect_native_data_type",
                Value::Object(input),
                &open_options(options),
            )
        }
        "inspect-native-instruction" => run_direct_analysis(
            runner,
            arg_str(args, "path"),
            "inspect_native_instruction",
            json!({ "address": arg_str(args, "address") }),
            &open_options(options),
        ),
        "resolve-native-call-targets" => run_direct_analysis(
            runner,
            arg_str(args, "path"),
            "resolve_native_call_targets",
            json!({ "address": arg_str(args, "address") }),
            &open_options(options),
        ),
        "inspect-native-api" => run_direct_analysis(
            runner,
            arg_str(args, "path"),
            "inspect_native_api",
            json!({ "procedure": arg_str(args, "address") }),
            &open_options(options),
        ),
        "trace-native-ui-action" => {
            let mut input = Map::new();
            input.insert("action".to_owned(), json!(arg_str(args, "action")));
            copy(
                &mut input,
                options,
                &[
                    ("maxDepth", "max_depth"),
                    ("maxNodes", "max_nodes"),
                    ("maxEdges", "max_edges"),
                ],
            );
            run_direct_analysis(
                runner,
                arg_str(args, "path"),
                "trace_native_ui_action",
                Value::Object(input),
                &open_options(options),
            )
        }
        "inspect-native-dispatch-metadata" => {
            let mut input = Map::new();
            copy(&mut input, options, &[("maxRecords", "max_records")]);
            run_direct_analysis(
                runner,
                arg_str(args, "path"),
                "inspect_native_dispatch_metadata",
                Value::Object(input),
                &open_options(options),
            )
        }
        "annotate-native-function" => {
            let mut input = Map::new();
            input.insert("procedure".to_owned(), json!(arg_str(args, "procedure")));
            copy(
                &mut input,
                options,
                &[
                    ("name", "name"),
                    ("comment", "comment"),
                    ("inline-comment", "inline_comment"),
                ],
            );
            run_direct_analysis(
                runner,
                arg_str(args, "path"),
                "annotate_native_function",
                Value::Object(input),
                &open_options(options),
            )
        }

        // ---- utility / native providers -----------------------------------
        "capabilities" | "providers" => match outcome(runner.invoke("binary_session", json!({}))) {
            Ok(value) => value,
            Err(projection) => object([("error", projection)]),
        },
        "inspect-macho" => {
            run_provider_analysis(runner, arg_str(args, "path"), "inspect_macho", json!({}))
        }
        "inspect-signature" => run_provider_analysis(
            runner,
            arg_str(args, "path"),
            "inspect_signature",
            json!({}),
        ),
        "list-architectures" => run_provider_analysis(
            runner,
            arg_str(args, "path"),
            "list_architectures",
            json!({}),
        ),
        "inspect-plist" => {
            let mut input = Map::new();
            if let Some(relative) = get_str(options, "relativePath") {
                input.insert("path".to_owned(), Value::String(relative));
            }
            run_provider_analysis(
                runner,
                arg_str(args, "path"),
                "inspect_plist",
                Value::Object(input),
            )
        }
        "demangle-swift" => run_provider_analysis(
            runner,
            arg_str(args, "path"),
            "demangle_swift",
            json!({ "symbols": args.get("symbols").cloned().unwrap_or(Value::Array(vec![])) }),
        ),
        "observe-native-ui" => provider(
            runner,
            "observe_native_ui",
            arg_str(args, "path"),
            options,
            &[],
            &[("windowId", "window_id"), ("maxNodes", "max_nodes")],
            vec![],
        ),
        "capture-native-ui-scenario" => run_capture_native_ui_scenario(runner, args, options),
        "import-reference-source" => {
            crate::application_commands::import_reference_source(runner, args, options)
        }

        // ---- evidence -----------------------------------------------------
        "evidence-import" => match outcome(runner.invoke(
            "import_evidence_bundle",
            json!({ "path": absolute_caller_path(arg_str(args, "path")) }),
        )) {
            Ok(value) => value,
            Err(projection) => cli_error(projection),
        },
        "evidence-export" => run_evidence_export(runner, args, options),
        "compare" => match outcome(runner.invoke(
            "compare_bundles",
            json!({
                "left_bundle_path": absolute_caller_path(arg_str(args, "left")),
                "right_bundle_path": absolute_caller_path(arg_str(args, "right")),
            }),
        )) {
            Ok(value) => value,
            Err(projection) => cli_error(projection),
        },

        // ---- artifact (open / close) --------------------------------------
        "inspect-artifact" => provider(
            runner,
            "inspect_artifact",
            arg_str(args, "path"),
            options,
            &[],
            &[("integrityPolicy", "integrity_policy")],
            vec![],
        ),
        "extract-artifact" => provider(
            runner,
            "extract_artifact",
            arg_str(args, "path"),
            options,
            &[],
            &[("integrityPolicy", "integrity_policy")],
            vec![],
        ),
        "decode-interface-builder" => provider(
            runner,
            "decode_interface_builder",
            arg_str(args, "path"),
            options,
            &[],
            &[
                ("maxDocuments", "max_documents"),
                ("maxObjects", "max_objects"),
                ("maxConnections", "max_connections"),
            ],
            vec![],
        ),
        "inspect-keyed-archive" => provider(
            runner,
            "inspect_keyed_archive",
            arg_str(args, "path"),
            options,
            &[],
            &[],
            vec![("path", json!(arg_str(args, "archive")))],
        ),
        "inspect-asset-catalog" => provider(
            runner,
            "inspect_asset_catalog",
            arg_str(args, "path"),
            options,
            &[],
            &[],
            vec![],
        ),
        "trace-dylib-resolution" => provider(
            runner,
            "trace_dylib_resolution",
            arg_str(args, "path"),
            options,
            &[],
            &[("root", "roots")],
            vec![],
        ),

        // ---- managed ------------------------------------------------------
        "inspect-managed-artifact" => run_provider_analysis(
            runner,
            arg_str(args, "path"),
            "inspect_managed_artifact",
            json!({}),
        ),
        "inspect-managed-members" => provider(
            runner,
            "inspect_managed_members",
            arg_str(args, "path"),
            options,
            &[],
            &[("type", "type_names")],
            vec![],
        ),
        "inspect-managed-native-boundaries" => run_provider_analysis(
            runner,
            arg_str(args, "path"),
            "inspect_managed_native_boundaries",
            json!({}),
        ),
        "compare-managed-members" => run_compare_managed_members(runner, args),
        "verify-managed-native-boundaries" => json_whole(
            runner,
            "verify_managed_native_boundaries",
            args,
            "verify_managed_native_boundaries",
        ),
        "import-managed-reconstruction" => json_whole(
            runner,
            "import_managed_reconstruction",
            args,
            "import_managed_reconstruction",
        ),
        "project-managed-application-graph" => json_whole(
            runner,
            "project_managed_application_graph",
            args,
            "project_managed_application_graph",
        ),

        // ---- single-file provider-neutral tools ---------------------------
        "inspect-go-binary" => direct(runner, "inspect_go_binary", args, options, &["path"], &[]),
        "inspect-rust-binary" => {
            direct(runner, "inspect_rust_binary", args, options, &["path"], &[])
        }
        "inspect-il2cpp-metadata" => {
            run_direct_evidence(runner, "inspect_il2cpp_metadata", args, options, &[])
        }
        "inspect-desktop-application" => {
            run_direct_evidence(runner, "inspect_desktop_application", args, options, &[])
        }
        "inspect-sqlite-database" => direct(
            runner,
            "inspect_sqlite_database",
            args,
            options,
            &["path"],
            &[
                ("column", "columns"),
                ("schemaScope", "schema_scope"),
                ("rowLimit", "row_limit"),
            ],
        ),
        "inspect-binary-layout" => direct(
            runner,
            "inspect_binary_layout",
            args,
            options,
            &["path"],
            &[],
        ),
        "inspect-pe-resources" => direct(
            runner,
            "inspect_pe_resources",
            args,
            options,
            &["path"],
            &[
                ("maxFileBytes", "max_file_bytes"),
                ("maxEntries", "max_entries"),
            ],
        ),
        "inspect-recorded-crash" => direct(
            runner,
            "inspect_recorded_crash",
            args,
            options,
            &["path"],
            &[("debuggerContext", "include_debugger_context")],
        ),
        "inspect-dart-aot" => direct(runner, "inspect_dart_aot", args, options, &["path"], &[]),
        "identify-flutter-build" => direct(
            runner,
            "identify_flutter_build",
            args,
            options,
            &["path"],
            &[],
        ),
        "inspect-pcap-capture" => direct(
            runner,
            "inspect_pcap_capture",
            args,
            options,
            &["path"],
            &[],
        ),
        "inspect-pcap-client" => direct(runner, "inspect_pcap_client", args, options, &[], &[]),
        "inspect-evm-interface" => direct(
            runner,
            "inspect_evm_interface",
            args,
            options,
            &["path"],
            &[],
        ),
        "inspect-wasm-artifact" => direct(
            runner,
            "inspect_wasm_artifact",
            args,
            options,
            &["path", "glue_paths", "candidate_paths"],
            &[],
        ),
        "compare-wasm-interfaces" => json_whole(
            runner,
            "compare_wasm_interfaces",
            args,
            "compare_wasm_interfaces",
        ),
        "inspect-firmware-regions" => direct(
            runner,
            "inspect_firmware_regions",
            args,
            options,
            &["path"],
            &[],
        ),
        "extract-firmware" => direct(
            runner,
            "extract_firmware",
            args,
            options,
            &["path", "outputDirectory"],
            &[
                ("maxDepth", "max_depth"),
                ("maxOutputBytes", "max_output_bytes"),
                ("maxOutputFiles", "max_output_files"),
            ],
        ),

        // ---- android / apktool / jeb --------------------------------------
        "inspect-android-package" => direct(
            runner,
            "inspect_android_package",
            args,
            options,
            &["path"],
            &[],
        ),
        "search-android-classes" => direct(
            runner,
            "search_android_classes",
            args,
            options,
            &["path"],
            &[],
        ),
        "inspect-android-class" => direct(
            runner,
            "inspect_android_class",
            args,
            options,
            &["path"],
            &[("className", "class_name")],
        ),
        "inspect-android-method" => direct(
            runner,
            "inspect_android_method",
            args,
            options,
            &["path"],
            &[
                ("className", "class_name"),
                ("methodName", "method_name"),
                ("overloadIndex", "overload_index"),
            ],
        ),
        "trace-android-references" => direct(
            runner,
            "trace_android_references",
            args,
            options,
            &["path"],
            &[
                ("className", "class_name"),
                ("methodName", "method_name"),
                ("overloadIndex", "overload_index"),
            ],
        ),
        "inspect-apktool-client" => {
            direct(runner, "inspect_apktool_client", args, options, &[], &[])
        }
        "decode-android-resources" => direct(
            runner,
            "decode_android_resources",
            args,
            options,
            &["path"],
            &[("strings", "include_strings")],
        ),
        "inspect-jeb-client" => direct(runner, "inspect_jeb_client", args, options, &[], &[]),
        "open-jeb-project" => direct(runner, "open_jeb_project", args, options, &["path"], &[]),
        "list-jeb-units" => direct(runner, "list_jeb_units", args, options, &[], &[]),
        "decompile-jeb-item" => direct(runner, "decompile_jeb_item", args, options, &[], &[]),

        // ---- captures / signals -------------------------------------------
        "inspect-packet-capture" => run_packet_capture(runner, args, options),
        "inspect-packet-fields" => run_packet_fields(runner, options),
        "decode-signal-recording" => run_signal_recording(runner, args, options),
        "inspect-signal-decoders" => run_signal_decoders(runner, options),
        "capture-process" => run_capture_process(runner, args),
        "compare-process-captures" => run_compare_process_captures(runner, args),

        // ---- cutter / frida / debug ---------------------------------------
        "list-cutter-sessions" => direct(runner, "list_cutter_sessions", args, options, &[], &[]),
        "cutter-command" => run_cutter_command(runner, args, options),
        "list-frida-devices" => run_frida_list(runner, "list_frida_devices", options, false),
        "list-frida-processes" => run_frida_list(runner, "list_frida_processes", options, true),
        "instrument-with-frida" => run_frida_instrument(runner, args, options),
        "inspect-with-objdump" => direct(
            runner,
            "inspect_with_objdump",
            args,
            options,
            &["path"],
            &[("followDebugLinks", "follow_debug_links")],
        ),
        "list-objdump-architectures" => match outcome(runner.invoke(
            "inspect_with_objdump",
            json!({ "operation": "architectures" }),
        )) {
            Ok(value) => value,
            Err(projection) => projection,
        },
        "execute-rizin-command" => direct(
            runner,
            "execute_rizin_command",
            args,
            options,
            &["path"],
            &[],
        ),
        "debug-with-gdb" => crate::application_commands::debug_with_gdb(runner, args, options),
        "debug-with-rizin" => crate::application_commands::debug_with_rizin(runner, args, options),

        // ---- browser / web / electron / js runtime ------------------------
        "list-browser-targets" => direct(
            runner,
            "list_browser_targets",
            args,
            options,
            &[],
            &[("endpoint", "cdp_endpoint")],
        ),
        "inspect-web-page" => direct(
            runner,
            "inspect_web_page",
            args,
            options,
            &[],
            &web_renames(),
        ),
        "analyze-web-bundle" => direct(
            runner,
            "analyze_web_bundle",
            args,
            options,
            &[],
            &web_renames(),
        ),
        "observe-web-session" => direct(
            runner,
            "observe_web_session",
            args,
            options,
            &[],
            &web_renames(),
        ),
        "observe-web-execution" => direct(
            runner,
            "observe_web_execution",
            args,
            options,
            &[],
            &web_renames(),
        ),
        "discover-webmcp-tools" => direct(
            runner,
            "discover_webmcp_tools",
            args,
            options,
            &[],
            &web_renames(),
        ),
        "inspect-web-event-listeners" => direct(
            runner,
            "inspect_web_event_listeners",
            args,
            options,
            &[],
            &web_renames(),
        ),
        "capture-web-screenshot" => direct(
            runner,
            "capture_web_screenshot",
            args,
            options,
            &[],
            &web_renames(),
        ),
        "compare-web-captures" => run_compare_web_captures(runner, args, options),
        "compare-web-screenshots" => run_compare_web_screenshots(runner, args, options),
        "inspect-web-network-capture" => direct(
            runner,
            "inspect_web_network_capture",
            args,
            options,
            &["capturePath"],
            &[
                ("record", "record_ordinals"),
                ("sensitiveValue", "sensitive_values"),
            ],
        ),
        "export-web-scripts" => direct(
            runner,
            "export_web_scripts",
            args,
            options,
            &["capturePath", "outputDirectory"],
            &[],
        ),
        "recover-javascript-sources" => direct(
            runner,
            "recover_javascript_sources",
            args,
            options,
            &["path", "outputDirectory", "additionalPath"],
            &[("additionalPath", "additional_paths")],
        ),
        "trace-web-source-location" => run_trace_web_source_location(runner, args),
        "trace-web-module-imports" => run_trace_web_module_imports(runner, args, options),
        "analyze-javascript-application" => {
            run_analyze_javascript_application(runner, args, options)
        }
        "reconcile-javascript-runtime" => json_whole(
            runner,
            "reconcile_javascript_runtime",
            args,
            "reconcile_javascript_runtime",
        ),
        "list-electron-targets" => direct(
            runner,
            "list_electron_targets",
            args,
            options,
            &[],
            &[("endpoint", "cdp_endpoint")],
        ),
        "inspect-electron-fuses" => direct(
            runner,
            "inspect_electron_fuses",
            args,
            options,
            &["path"],
            &[],
        ),
        "inspect-electron-page" => direct(
            runner,
            "inspect_electron_page",
            args,
            options,
            &[],
            &[("endpoint", "cdp_endpoint"), ("targetId", "target_id")],
        ),
        "capture-electron-scenario" => json_whole(
            runner,
            "capture_electron_scenario",
            args,
            "capture_electron_scenario",
        ),
        "capture-browser-scenario" => json_whole(
            runner,
            "capture_browser_scenario",
            args,
            "capture_browser_scenario",
        ),
        "list-javascript-runtime-targets" => direct(
            runner,
            "list_javascript_runtime_targets",
            args,
            options,
            &[],
            &[("endpoint", "inspector_endpoint")],
        ),
        "observe-javascript-runtime" => direct(
            runner,
            "observe_javascript_runtime",
            args,
            options,
            &[],
            &[
                ("endpoint", "inspector_endpoint"),
                ("targetId", "target_id"),
                ("runtimeKind", "runtime_kind"),
            ],
        ),

        // ---- application graphs / semantics (whole-JSON) ------------------
        "project-android-application-graph" => json_whole(
            runner,
            "project_android_application_graph",
            args,
            "project_android_application_graph",
        ),
        "project-apple-application-graph" => json_whole(
            runner,
            "project_apple_application_graph",
            args,
            "project_apple_application_graph",
        ),
        "project-harmony-application-graph" => json_whole(
            runner,
            "project_harmony_application_graph",
            args,
            "project_harmony_application_graph",
        ),
        "trace-application-feature" => json_whole(
            runner,
            "trace_application_feature",
            args,
            "trace_application_feature",
        ),
        "trace-javascript-semantics" => json_whole(
            runner,
            "trace_javascript_semantics",
            args,
            "trace_javascript_semantics",
        ),
        "compare-application-versions" => json_whole(
            runner,
            "compare_application_versions",
            args,
            "compare_application_versions",
        ),
        "compare-source-to-bundle" => json_whole(
            runner,
            "compare_source_to_bundle",
            args,
            "compare_source_to_bundle",
        ),
        "compare-javascript-export-shapes" => json_whole(
            runner,
            "compare_javascript_export_shapes",
            args,
            "compare_javascript_export_shapes",
        ),
        "build-reconstruction-obligation-ledger" => json_whole(
            runner,
            "build_reconstruction_obligation_ledger",
            args,
            "build_reconstruction_obligation_ledger",
        ),
        "evaluate-reconstruction-coverage" => json_whole(
            runner,
            "evaluate_reconstruction_coverage",
            args,
            "evaluate_reconstruction_coverage",
        ),

        // ---- analysis views -----------------------------------------------
        "inspect-analysis-view" => json_whole(
            runner,
            "inspect_analysis_view",
            args,
            "inspect_analysis_view",
        ),
        "inspect-evidence-bundle" => {
            crate::application_commands::inspect_evidence_bundle(runner, args)
        }

        // ---- native call tracing ------------------------------------------
        "observe-native-calls" => run_observe_native_calls(runner, args),

        // ---- adb ----------------------------------------------------------
        "inspect-adb-client" => direct(runner, "inspect_adb_client", args, options, &[], &[]),
        "list-adb-devices" => direct(runner, "list_adb_devices", args, options, &[], &[]),
        "inspect-adb-device" => direct(runner, "inspect_adb_device", args, options, &[], &[]),
        "list-adb-packages" => direct(runner, "list_adb_packages", args, options, &[], &[]),
        "pull-adb-package" => direct(
            runner,
            "pull_adb_package",
            args,
            options,
            &["output-directory"],
            &[],
        ),
        "read-adb-logcat" => direct(runner, "read_adb_logcat", args, options, &[], &[]),
        "inspect-adb-package" => direct(runner, "inspect_adb_package", args, options, &[], &[]),
        "pull-adb-file" => direct(
            runner,
            "pull_adb_file",
            args,
            options,
            &["output-directory"],
            &[],
        ),
        "push-adb-file" => direct(runner, "push_adb_file", args, options, &["local-path"], &[]),
        "capture-adb-screen" => direct(
            runner,
            "capture_adb_screen",
            args,
            options,
            &["output-directory"],
            &[],
        ),
        "list-adb-processes" => direct(runner, "list_adb_processes", args, options, &[], &[]),
        "list-adb-directory" => direct(runner, "list_adb_directory", args, options, &[], &[]),
        "list-adb-features" => direct(runner, "list_adb_features", args, options, &[], &[]),
        "list-adb-services" => direct(runner, "list_adb_services", args, options, &[], &[]),
        "inspect-adb-display" => direct(runner, "inspect_adb_display", args, options, &[], &[]),
        "inspect-adb-window" => direct(runner, "inspect_adb_window", args, options, &[], &[]),
        "read-adb-setting" => direct(runner, "read_adb_setting", args, options, &[], &[]),
        "collect-adb-bugreport" => direct(
            runner,
            "collect_adb_bugreport",
            args,
            options,
            &["output-directory"],
            &[],
        ),
        "resolve-adb-packages" => direct(runner, "resolve_adb_packages", args, options, &[], &[]),
        "install-adb-package" => direct(
            runner,
            "install_adb_package",
            args,
            options,
            &["apk-path"],
            &[],
        ),
        "uninstall-adb-package" => direct(runner, "uninstall_adb_package", args, options, &[], &[]),
        "start-adb-app" => direct(runner, "start_adb_app", args, options, &[], &[]),
        "start-adb-activity" => run_start_adb_activity(runner, args, options),
        "stop-adb-app" => direct(runner, "stop_adb_app", args, options, &[], &[]),

        // ---- maintenance / environment (application-only) -----------------
        "setup" => crate::maintenance::setup(
            &crate::maintenance::SetupOptions {
                approved: options.get("yes").and_then(Value::as_bool).unwrap_or(false),
                install_hopper: options
                    .get("installHopper")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
                client_ids: option_strings(options, "client"),
                skill_client_ids: option_strings(options, "skillClient"),
                all_detected_clients: options
                    .get("allDetected")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
                install_skill: options.get("skill").and_then(Value::as_bool),
                dry_run: options
                    .get("dryRun")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
                accessible: options
                    .get("accessible")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
            },
            runner,
        ),
        "doctor" => crate::doctor_commands::run(options, runner),
        "uninstall" => crate::maintenance::uninstall(
            options
                .get("purgeData")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            runner,
        ),
        "update" => crate::maintenance::update(runner),
        "environment-export" => crate::environment_export_commands::export(args, options),
        "environment-serve" => {
            crate::environment_commands::serve(args, options, &runner.cancellation)
        }

        _ => unavailable(name),
    };

    match rea_mcp::raw_cli_output(&value) {
        Some(raw) => CommandOutput::Raw(
            RawValue::from_string(raw.to_owned()).expect("raw CLI result remains valid JSON"),
        ),
        None => CommandOutput::Value(value),
    }
}

fn web_renames() -> [(&'static str, &'static str); 2] {
    [("endpoint", "cdp_endpoint"), ("targetId", "target_id")]
}

// ---------------------------------------------------------------------------
// Command-specific handlers
// ---------------------------------------------------------------------------
fn run_selector_tool(
    runner: &Runner<'_>,
    args: &Value,
    options: &Value,
    tool: &str,
    option: &str,
    build: impl FnOnce(String) -> Value,
) -> Value {
    match resolve_selector(
        get_str(args, "address").as_deref(),
        get_str(options, option).as_deref(),
        option,
        tool,
    ) {
        Ok(selector) => run_direct_analysis(
            runner,
            arg_str(args, "path"),
            tool,
            build(selector),
            &open_options(options),
        ),
        Err(projection) => projection,
    }
}

fn run_decompile(runner: &Runner<'_>, args: &Value, options: &Value) -> Value {
    let named = get_str(options, "procedure");
    match resolve_selector(
        get_str(args, "address").as_deref(),
        named.as_deref(),
        "procedure",
        "procedure_pseudo_code",
    ) {
        Ok(selector) => run_direct_analysis(
            runner,
            arg_str(args, "path"),
            "procedure_pseudo_code",
            json!({ "procedure": selector }),
            &open_options(options),
        ),
        Err(projection) => projection,
    }
}

fn run_search(runner: &Runner<'_>, args: &Value, options: &Value) -> Value {
    let kind = get_str(options, "kind").unwrap_or_else(|| "strings".to_owned());
    let tool = if kind == "strings" {
        "search_strings"
    } else {
        "search_procedures"
    };
    match resolve_selector(
        get_str(args, "pattern").as_deref(),
        get_str(options, "pattern").as_deref(),
        "pattern",
        tool,
    ) {
        Ok(pattern) => {
            let mut input = Map::new();
            input.insert("pattern".to_owned(), Value::String(pattern));
            input.insert(
                "mode".to_owned(),
                options.get("mode").cloned().unwrap_or(json!("literal")),
            );
            input.insert(
                "case_sensitive".to_owned(),
                options
                    .get("caseSensitive")
                    .cloned()
                    .unwrap_or(Value::Bool(false)),
            );
            run_direct_analysis(
                runner,
                arg_str(args, "path"),
                tool,
                Value::Object(input),
                &open_options(options),
            )
        }
        Err(projection) => projection,
    }
}

fn run_trace(runner: &Runner<'_>, args: &Value, options: &Value) -> Value {
    match resolve_selector(
        get_str(args, "query").as_deref(),
        get_str(options, "query").as_deref(),
        "query",
        "trace_feature",
    ) {
        Ok(query) => {
            let input = json!({
                "query": query,
                "case_sensitive": options.get("caseSensitive").cloned().unwrap_or(Value::Bool(false)),
            });
            run_direct_analysis(
                runner,
                arg_str(args, "path"),
                "trace_feature",
                input,
                &open_options(options),
            )
        }
        Err(projection) => projection,
    }
}

fn run_xrefs(runner: &Runner<'_>, args: &Value, options: &Value) -> Value {
    let selector = match resolve_selector(
        get_str(args, "address").as_deref(),
        get_str(options, "address").as_deref(),
        "address",
        "xrefs",
    ) {
        Ok(value) => value,
        Err(projection) => return projection,
    };
    run_custom(
        runner,
        arg_str(args, "path"),
        &open_options(options),
        |runner| {
            let address = resolve_xrefs_address(runner, &selector)?;
            outcome(runner.invoke("xrefs", json!({ "address": address })))
        },
    )
}

fn run_analyze(runner: &Runner<'_>, args: &Value, options: &Value) -> Value {
    let path = arg_str(args, "path");
    let native_flag = NATIVE_OPEN
        .iter()
        .any(|key| *key != "snapshot" && present(options, key))
        || present(options, "snapshot");
    let routes_js = !native_flag && is_javascript_application_path(path);
    if routes_js {
        let mut input = Map::new();
        input.insert(
            "input_path".to_owned(),
            Value::String(absolute_caller_path(path)),
        );
        input.insert(
            "integrity_policy".to_owned(),
            options
                .get("integrityPolicy")
                .cloned()
                .unwrap_or(json!("fail")),
        );
        if let Some(sources) = options.get("sourcePath") {
            input.insert("source_paths".to_owned(), sources.clone());
        }
        return match outcome(runner.invoke("analyze_javascript_application", Value::Object(input)))
        {
            Ok(value) => value,
            Err(projection) => projection,
        };
    }
    if present(options, "sourcePath") {
        return input_projection(
            "analyze_javascript_application",
            &["source_paths"],
            "invalid_value",
            "Source selection requires the static JavaScript ASAR/directory analysis lane."
                .to_owned(),
            None,
        );
    }
    if present(options, "integrityPolicy") {
        return input_projection(
            "analyze_javascript_application",
            &["integrity_policy"],
            "invalid_value",
            "An integrity policy requires the static JavaScript ASAR/directory analysis lane; binary_overview accepts no input.".to_owned(),
            None,
        );
    }
    run_direct_analysis(
        runner,
        path,
        "binary_overview",
        json!({}),
        &open_options(options),
    )
}

fn run_analyze_javascript_application(runner: &Runner<'_>, args: &Value, options: &Value) -> Value {
    let mut input = Map::new();
    input.insert(
        "input_path".to_owned(),
        Value::String(absolute_caller_path(arg_str(args, "path"))),
    );
    copy(
        &mut input,
        options,
        &[
            ("maxSemanticNodes", "max_semantic_nodes"),
            ("maxSemanticNodesPerFile", "max_semantic_nodes_per_file"),
            ("maxSemanticUnknowns", "max_semantic_unknowns"),
            (
                "maxSemanticUnknownsPerFile",
                "max_semantic_unknowns_per_file",
            ),
            ("maxHeapMb", "max_heap_mb"),
            ("analysisTimeoutMs", "analysis_timeout_ms"),
            ("artifactFormat", "format"),
            ("integrityPolicy", "integrity_policy"),
        ],
    );
    if let Some(sources) = options.get("sourcePath") {
        input.insert("source_paths".to_owned(), sources.clone());
    }
    match outcome(runner.invoke("analyze_javascript_application", Value::Object(input))) {
        Ok(value) => value,
        Err(projection) => projection,
    }
}

fn run_direct_evidence(
    runner: &Runner<'_>,
    tool: &str,
    args: &Value,
    options: &Value,
    renames: &[(&str, &str)],
) -> Value {
    let detail = get_str(options, "detail").unwrap_or_else(|| "complete".to_owned());
    let evidence_output = get_str(options, "evidence_output");
    if detail == "summary" && evidence_output.is_none() {
        return input_projection(
            tool,
            &["evidence_output"],
            "invalid_value",
            "Summary delivery requires --evidence_output so complete source Evidence remains available.".to_owned(),
            None,
        );
    }
    let mut input = Map::new();
    input.insert(
        "path".to_owned(),
        Value::String(absolute_caller_path(arg_str(args, "path"))),
    );
    input.insert("detail".to_owned(), Value::String("complete".to_owned()));
    if let Some(object) = options.as_object() {
        for (key, value) in object {
            if key == "detail" || key == "evidence_output" {
                continue;
            }
            input.insert(renamed(key, renames), value.clone());
        }
    }
    let complete = match outcome(runner.invoke(tool, Value::Object(input))) {
        Ok(value) => value,
        Err(projection) => return projection,
    };
    let Some(evidence_output) = evidence_output else {
        return complete;
    };
    if complete.get("evidence_id").is_none() {
        return complete;
    }
    let receipt = match outcome(runner.invoke(
        "export_evidence_bundle",
        json!({ "path": absolute_caller_path(&evidence_output), "overwrite": false }),
    )) {
        Ok(value) => value,
        Err(projection) => return projection,
    };
    if detail == "summary" {
        let summary = outcome(runner.invoke(
            "inspect_analysis_view",
            json!({ "source": { "kind": "inline", "evidence": complete }, "view": { "kind": "summary" } }),
        ));
        match summary {
            Ok(summary) => object([("summary", summary), ("evidence_bundle", receipt)]),
            Err(projection) => projection,
        }
    } else {
        complete
    }
}

fn run_evidence_export(runner: &Runner<'_>, args: &Value, options: &Value) -> Value {
    let source = absolute_caller_path(arg_str(args, "source"));
    if let Err(projection) =
        outcome(runner.invoke("import_evidence_bundle", json!({ "path": source })))
    {
        return cli_error(projection);
    }
    let overwrite = options
        .get("overwrite")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    match outcome(runner.invoke(
        "export_evidence_bundle",
        json!({ "path": absolute_caller_path(arg_str(args, "output")), "overwrite": overwrite }),
    )) {
        Ok(value) => value,
        Err(projection) => cli_error(projection),
    }
}

fn run_capture_native_ui_scenario(runner: &Runner<'_>, args: &Value, options: &Value) -> Value {
    let mut input = Map::new();
    copy(
        &mut input,
        options,
        &[
            ("pid", "pid"),
            ("windowId", "window_id"),
            ("screenshot", "screenshot"),
            ("accessibility", "accessibility"),
            ("maxNodes", "max_nodes"),
        ],
    );
    if let Some(steps) = get_str(options, "steps") {
        match serde_json::from_str::<Value>(&steps) {
            Ok(value) => {
                input.insert("steps".to_owned(), value);
            }
            Err(_) => {
                return labelled(
                    "Application workflow failed",
                    input_projection(
                        "capture_native_ui_scenario",
                        &["steps"],
                        "invalid_format",
                        "JSON".to_owned(),
                        Some("JSON"),
                    ),
                );
            }
        }
    }
    run_provider_analysis(
        runner,
        arg_str(args, "path"),
        "capture_native_ui_scenario",
        Value::Object(input),
    )
}

fn run_compare_managed_members(runner: &Runner<'_>, args: &Value) -> Value {
    let left = match read_json_input(arg_str(args, "leftPath"), "compare_managed_members") {
        Ok(value) => value,
        Err(error) => return error,
    };
    let right = match read_json_input(arg_str(args, "rightPath"), "compare_managed_members") {
        Ok(value) => value,
        Err(error) => return error,
    };
    match outcome(runner.invoke(
        "compare_managed_members",
        json!({ "left": left, "right": right }),
    )) {
        Ok(value) => value,
        Err(projection) => projection,
    }
}

fn run_packet_capture(runner: &Runner<'_>, args: &Value, options: &Value) -> Value {
    let all_matches = options
        .get("all_matches")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let mut input = Map::new();
    input.insert(
        "path".to_owned(),
        Value::String(absolute_caller_path(arg_str(args, "path"))),
    );
    if let Some(object) = options.as_object() {
        for (key, value) in object {
            if key == "all_matches" {
                continue;
            }
            if all_matches && key == "match_limit" {
                continue;
            }
            input.insert(key.clone(), value.clone());
        }
    }
    if all_matches {
        input.insert("match_limit".to_owned(), Value::Null);
    }
    match outcome(runner.invoke("inspect_packet_capture", Value::Object(input))) {
        Ok(value) => value,
        Err(projection) => projection,
    }
}

fn run_packet_fields(runner: &Runner<'_>, options: &Value) -> Value {
    let all = options.get("all").and_then(Value::as_bool).unwrap_or(false);
    let mut input = Map::new();
    if let Some(object) = options.as_object() {
        for (key, value) in object {
            if key == "all" {
                continue;
            }
            if all && key == "limit" {
                continue;
            }
            input.insert(key.clone(), value.clone());
        }
    }
    if all {
        input.insert("limit".to_owned(), Value::Null);
    }
    match outcome(runner.invoke("inspect_packet_fields", Value::Object(input))) {
        Ok(value) => value,
        Err(projection) => projection,
    }
}

fn run_signal_recording(runner: &Runner<'_>, args: &Value, options: &Value) -> Value {
    let all_lines = options
        .get("all_lines")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let mut input = Map::new();
    input.insert(
        "path".to_owned(),
        Value::String(absolute_caller_path(arg_str(args, "path"))),
    );
    if let Some(object) = options.as_object() {
        for (key, value) in object {
            if key == "all_lines" {
                continue;
            }
            if all_lines && key == "line_limit" {
                continue;
            }
            input.insert(key.clone(), value.clone());
        }
    }
    if all_lines {
        input.insert("line_limit".to_owned(), Value::Null);
    }
    match outcome(runner.invoke("decode_signal_recording", Value::Object(input))) {
        Ok(value) => value,
        Err(projection) => projection,
    }
}

fn run_signal_decoders(runner: &Runner<'_>, options: &Value) -> Value {
    let all = options.get("all").and_then(Value::as_bool).unwrap_or(false);
    let mut input = Map::new();
    if let Some(object) = options.as_object() {
        for (key, value) in object {
            if key == "all" {
                continue;
            }
            if all && key == "limit" {
                continue;
            }
            input.insert(key.clone(), value.clone());
        }
    }
    if all {
        input.insert("limit".to_owned(), Value::Null);
    }
    match outcome(runner.invoke("inspect_signal_decoders", Value::Object(input))) {
        Ok(value) => value,
        Err(projection) => projection,
    }
}

fn run_capture_process(runner: &Runner<'_>, args: &Value) -> Value {
    match read_json_input(arg_str(args, "scenario"), "capture_process_scenario") {
        Ok(scenario) => match outcome(runner.invoke("capture_process_scenario", scenario)) {
            Ok(value) => value,
            Err(projection) => projection,
        },
        Err(error) => error,
    }
}

fn run_compare_process_captures(runner: &Runner<'_>, args: &Value) -> Value {
    let left = match read_json_input(arg_str(args, "left"), "compare_process_captures") {
        Ok(value) => value,
        Err(error) => return error,
    };
    let right = match read_json_input(arg_str(args, "right"), "compare_process_captures") {
        Ok(value) => value,
        Err(error) => return error,
    };
    let mut input = Map::new();
    input.insert("left".to_owned(), left);
    input.insert("right".to_owned(), right);
    if let Some(trace) = get_str(args, "traceSpec") {
        match read_json_input(&trace, "compare_process_captures") {
            Ok(value) => {
                input.insert("trace_spec".to_owned(), value);
            }
            Err(error) => return error,
        }
    }
    match outcome(runner.invoke("compare_process_captures", Value::Object(input))) {
        Ok(value) => value,
        Err(projection) => projection,
    }
}

fn run_cutter_command(runner: &Runner<'_>, args: &Value, options: &Value) -> Value {
    let json_output = options
        .get("jsonOutput")
        .and_then(Value::as_bool)
        .or_else(|| options.get("json").and_then(Value::as_bool))
        .unwrap_or(false);
    let input = json!({
        "session_id": arg_str(args, "sessionId"),
        "expected_generation": args.get("expectedGeneration").cloned().unwrap_or(json!(0)),
        "command": arg_str(args, "command"),
        "json": json_output,
    });
    match outcome(runner.invoke("cutter_command", input)) {
        Ok(value) => value,
        Err(projection) => projection,
    }
}

fn frida_remote(options: &Value) -> Option<Value> {
    let address = get_str(options, "remoteAddress")?;
    let mut remote = Map::new();
    remote.insert("address".to_owned(), Value::String(address));
    copy(
        &mut remote,
        options,
        &[
            ("token", "token"),
            ("certificate", "certificate"),
            ("origin", "origin"),
            ("keepaliveInterval", "keepalive_interval"),
        ],
    );
    Some(Value::Object(remote))
}

fn run_frida_list(runner: &Runner<'_>, tool: &str, options: &Value, device: bool) -> Value {
    let mut input = Map::new();
    if let Some(remote) = frida_remote(options) {
        input.insert("remote".to_owned(), remote);
    } else if device && let Some(id) = get_str(options, "deviceId") {
        input.insert("device_id".to_owned(), Value::String(id));
    }
    match outcome(runner.invoke(tool, Value::Object(input))) {
        Ok(value) => value,
        Err(projection) => projection,
    }
}

fn run_frida_instrument(runner: &Runner<'_>, args: &Value, options: &Value) -> Value {
    let operation = "instrument_with_frida";
    let mode = arg_str(args, "mode");
    let target = arg_str(args, "target");
    if mode == "attach" && present(options, "argument") {
        return input_projection(
            operation,
            &["argument"],
            "invalid_value",
            "--argument is only valid in spawn mode; remove it when attaching to a process."
                .to_owned(),
            None,
        );
    }
    let has_script = present(options, "script");
    let has_file = present(options, "scriptFile");
    if has_script == has_file {
        return input_projection(
            operation,
            &["script"],
            "invalid_value",
            "Provide exactly one of --script or --script-file.".to_owned(),
            None,
        );
    }
    let mut input = Map::new();
    let remote = frida_remote(options);
    if let Some(remote) = &remote {
        input.insert("remote".to_owned(), remote.clone());
    } else {
        input.insert(
            "device_id".to_owned(),
            Value::String(get_str(options, "deviceId").unwrap_or_else(|| "local".to_owned())),
        );
    }
    if mode == "attach" {
        let numeric = target.parse::<u64>().ok().filter(|pid| *pid > 0);
        match numeric {
            Some(pid) => {
                input.insert("mode".to_owned(), Value::String("attach".to_owned()));
                input.insert("pid".to_owned(), Value::Number(pid.into()));
            }
            None => {
                return input_projection(
                    operation,
                    &["target"],
                    "invalid_value",
                    "attach mode needs a positive integer process ID.".to_owned(),
                    None,
                );
            }
        }
    } else {
        input.insert("mode".to_owned(), Value::String("spawn".to_owned()));
        input.insert("program".to_owned(), Value::String(target.to_owned()));
        if let Some(argv) = options.get("argument") {
            input.insert("argv".to_owned(), argv.clone());
        }
    }
    if let Some(file) = get_str(options, "scriptFile") {
        input.insert("source_kind".to_owned(), Value::String("file".to_owned()));
        input.insert("path".to_owned(), Value::String(file));
    } else {
        input.insert("source_kind".to_owned(), Value::String("inline".to_owned()));
        input.insert(
            "source".to_owned(),
            Value::String(get_str(options, "script").unwrap_or_default()),
        );
    }
    if let Some(duration) = options.get("durationMs") {
        input.insert("duration_ms".to_owned(), duration.clone());
    }
    match outcome(runner.invoke(operation, Value::Object(input))) {
        Ok(value) => value,
        Err(projection) => projection,
    }
}

fn run_start_adb_activity(runner: &Runner<'_>, args: &Value, options: &Value) -> Value {
    let mut extras = Vec::new();
    if let Some(entries) = options.get("extra").and_then(Value::as_array) {
        for (index, entry) in entries.iter().enumerate() {
            let text = entry.as_str().unwrap_or_default();
            let first = text.find(':');
            let second = first
                .and_then(|first| text[first + 1..].find(':').map(|offset| first + 1 + offset));
            match (first, second) {
                (Some(first), Some(second)) => {
                    extras.push(json!({
                        "type": &text[..first],
                        "key": &text[first + 1..second],
                        "value": &text[second + 1..],
                    }));
                }
                _ => {
                    return input_projection(
                        "start_adb_activity",
                        &["extras"],
                        "invalid_format",
                        "Expected --extra in type:key:value form.".to_owned(),
                        Some("type:key:value"),
                    )
                    .as_object()
                    .cloned()
                    .map(|mut projection| {
                        if let Some(issues) = projection
                            .get_mut("details")
                            .and_then(Value::as_object_mut)
                            .and_then(|details| details.get_mut("issues"))
                            .and_then(Value::as_array_mut)
                            && let Some(first_issue) = issues.first_mut()
                            && let Some(issue) = first_issue.as_object_mut()
                        {
                            issue.insert("path".to_owned(), json!(["extras", index]));
                        }
                        Value::Object(projection)
                    })
                    .unwrap_or_else(|| {
                        input_projection(
                            "start_adb_activity",
                            &["extras"],
                            "invalid_format",
                            "Expected --extra in type:key:value form.".to_owned(),
                            Some("type:key:value"),
                        )
                    });
                }
            }
        }
    }
    let mut input = Map::new();
    input.insert("serial".to_owned(), json!(arg_str(args, "serial")));
    input.insert("action".to_owned(), json!(arg_str(args, "action")));
    copy(
        &mut input,
        options,
        &[("data-uri", "data_uri"), ("component", "component")],
    );
    input.insert("extras".to_owned(), Value::Array(extras));
    match outcome(runner.invoke("start_adb_activity", Value::Object(input))) {
        Ok(value) => value,
        Err(projection) => projection,
    }
}

fn run_observe_native_calls(runner: &Runner<'_>, args: &Value) -> Value {
    let input = match read_json_input(arg_str(args, "inputJson"), "observe_native_calls") {
        Ok(value) => value,
        Err(error) => return error,
    };
    run_provider_analysis(runner, arg_str(args, "path"), "observe_native_calls", input)
}

fn run_trace_web_source_location(runner: &Runner<'_>, args: &Value) -> Value {
    let input = json!({
        "manifest_path": absolute_caller_path(arg_str(args, "manifestPath")),
        "script_index": args.get("scriptIndex").cloned().unwrap_or(json!(0)),
        "source_map": {
            "path": absolute_caller_path(arg_str(args, "sourceMapPath")),
            "url": arg_str(args, "sourceMapUrl"),
        },
        "generated_position": {
            "line": args.get("line").cloned().unwrap_or(json!(1)),
            "column": args.get("column").cloned().unwrap_or(json!(0)),
        },
    });
    match outcome(runner.invoke("trace_web_source_location", input)) {
        Ok(value) => value,
        Err(projection) => projection,
    }
}

fn run_trace_web_module_imports(runner: &Runner<'_>, args: &Value, options: &Value) -> Value {
    let mut input = Map::new();
    input.insert(
        "manifest_path".to_owned(),
        Value::String(absolute_caller_path(arg_str(args, "manifestPath"))),
    );
    input.insert(
        "script_index".to_owned(),
        args.get("scriptIndex").cloned().unwrap_or(json!(0)),
    );
    if let Some(importer) = get_str(options, "importerUrl") {
        input.insert("importer_url".to_owned(), Value::String(importer));
    }
    let import_map_path = get_str(options, "importMapPath");
    let import_map_base_url = get_str(options, "importMapBaseUrl");
    if import_map_path.is_some() || import_map_base_url.is_some() {
        let Some(map_path) = import_map_path else {
            return input_projection(
                "trace_web_module_imports",
                &["import_map", "path"],
                "missing_required",
                "importMapPath is required when importMapBaseUrl is provided.".to_owned(),
                Some("absolute filesystem path"),
            );
        };
        let Some(base_url) = import_map_base_url else {
            return input_projection(
                "trace_web_module_imports",
                &["import_map", "base_url"],
                "missing_required",
                "importMapBaseUrl is required when importMapPath is provided.".to_owned(),
                Some("HTTP or HTTPS URL"),
            );
        };
        input.insert(
            "import_map".to_owned(),
            json!({
                "path": absolute_caller_path(&map_path),
                "base_url": base_url,
            }),
        );
    }
    match outcome(runner.invoke("trace_web_module_imports", Value::Object(input))) {
        Ok(value) => value,
        Err(projection) => projection,
    }
}

fn run_compare_web_captures(runner: &Runner<'_>, args: &Value, options: &Value) -> Value {
    let before = match read_json_input(arg_str(args, "beforeJson"), "compare_web_captures") {
        Ok(value) => value,
        Err(error) => return error,
    };
    let after = match read_json_input(arg_str(args, "afterJson"), "compare_web_captures") {
        Ok(value) => value,
        Err(error) => return error,
    };
    let scenario = is_scenario_capture(&before) || is_scenario_capture(&after);
    let mut input = Map::new();
    if scenario {
        input.insert("before_scenario".to_owned(), before);
        input.insert("after_scenario".to_owned(), after);
        if let Some(normalization) = get_str(options, "normalizationJson") {
            if let Ok(value) = serde_json::from_str::<Value>(&normalization) {
                input.insert("normalization".to_owned(), value);
            } else if let Ok(value) = read_json_input(&normalization, "compare_web_captures") {
                input.insert("normalization".to_owned(), value);
            }
        }
    } else {
        input.insert("before".to_owned(), before);
        input.insert("after".to_owned(), after);
    }
    match outcome(runner.invoke("compare_web_captures", Value::Object(input))) {
        Ok(value) => value,
        Err(projection) => projection,
    }
}

fn is_scenario_capture(value: &Value) -> bool {
    let Some(object) = value.as_object() else {
        return false;
    };
    object.get("browser").is_some_and(Value::is_object)
        && object.get("scenario").is_some_and(Value::is_object)
        && object.get("steps").is_some_and(Value::is_array)
        && object.get("events").is_some_and(Value::is_object)
}

fn run_compare_web_screenshots(runner: &Runner<'_>, args: &Value, options: &Value) -> Value {
    let before = match read_json_input(arg_str(args, "beforeJson"), "compare_web_screenshots") {
        Ok(value) => value,
        Err(error) => return error,
    };
    let after = match read_json_input(arg_str(args, "afterJson"), "compare_web_screenshots") {
        Ok(value) => value,
        Err(error) => return error,
    };
    let input = json!({
        "before": before,
        "after": after,
        "channel_threshold": options.get("channelThreshold").cloned().unwrap_or(json!(0)),
    });
    match outcome(runner.invoke("compare_web_screenshots", input)) {
        Ok(value) => value,
        Err(projection) => projection,
    }
}
